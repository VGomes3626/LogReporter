from collections import defaultdict
from pathlib import Path
import re
import sys
from urllib.parse import unquote_plus


LOG_FILE = Path("access.log")
BRUTE_FORCE_THRESHOLD = 3


ANSI_RESET = "\033[0m"
ANSI_RED = "\033[31m"
ANSI_YELLOW = "\033[33m"
ANSI_CYAN = "\033[36m"
ANSI_BOLD = "\033[1m"


SQLI_PATTERNS = [
	re.compile(r"(?i)\bunion\s+select\b"),
	# classic UNION SELECT
	re.compile(r"(?i)\bunion\s+select\b"),
	# boolean-based SQLi like ' OR 1=1 or " OR 1=1
	re.compile(r"(?i)(?:'|\")\s*or\s*1\s*=\s*1"),
	re.compile(r"(?i)(?:'|\")\s*or\s*'1'\s*=\s*'1'"),
	# stacked queries or injected semicolons
	re.compile(r"(?i);\s*(?:select|insert|update|delete|drop|exec|execute)\b"),
	# time-based SQLi (WAITFOR DELAY, SLEEP)
	re.compile(r"(?i)\bwaitfor\s+delay\b"),
	re.compile(r"(?i)\bsleep\s*\(\s*\d+\s*\)"),
	# SQL comments or inline comment markers
	re.compile(r"(?i)--\s|/\*.*\*/"),
	# generic SQL keywords near suspicious characters
	re.compile(r"(?i)\b(select|union|insert|update|delete|drop|exec|execute)\b.*\bfrom\b"),
]

XSS_PATTERN = re.compile(r"(?i)<\s*script\b")

LOG_LINE_PATTERN = re.compile(
	r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[[^\]]+\]\s+"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+HTTP/[^\"]+"\s+(?P<status>\d{3})'
)


# in-memory alerts collected during analysis
ALERTS: list[tuple[int, str, str]] = []


def color(text: str, style: str) -> str:
	return f"{style}{text}{ANSI_RESET}"


def alert(line_number: int, attack_type: str, line: str) -> None:
	# store alert for possible export
	ALERTS.append((line_number, attack_type, line.rstrip()))
	print(color("[ALERTA]", ANSI_BOLD + ANSI_RED), end=" ")
	print(color(f"Linha {line_number}", ANSI_CYAN), end=" - ")
	print(color(attack_type, ANSI_YELLOW))
	print(f"  {line.rstrip()}\n")


def export_alerts_to_txt(path: Path) -> bool:
	try:
		with path.open("w", encoding="utf-8") as f:
			f.write("ALERTAS DETECTADOS\n")
			f.write("=================\n\n")
			for ln, typ, content in ALERTS:
				f.write(f"Linha {ln} - {typ}\n")
				f.write(f"{content}\n\n")
		return True
	except OSError:
		return False


def print_missing_file_help() -> None:
	print(
		color(
			"Arquivo 'access.log' não encontrado na pasta atual.",
			ANSI_BOLD + ANSI_RED,
		)
	)
	print("Crie o arquivo ao lado de 'reporter.py' e cole logs de teste para executar a análise local.")
	print("Depois execute novamente: python reporter.py")


def detect_sqli(raw_line: str, decoded_line: str) -> list[str]:
	# Check both raw and decoded representations to catch URL-encoded payloads
	for pattern in SQLI_PATTERNS:
		if pattern.search(raw_line) or pattern.search(decoded_line):
			return ["SQL Injection"]
	return []


def detect_xss(raw_line: str, decoded_line: str) -> list[str]:
	# Prefer decoded content for XSS detection (catches %3Cscript%3E)
	if XSS_PATTERN.search(decoded_line) or XSS_PATTERN.search(raw_line):
		return ["Cross-Site Scripting (XSS)"]
	return []


def detect_bruteforce(line: str, brute_force_counts: dict[tuple[str, str], int]) -> list[str]:
	match = LOG_LINE_PATTERN.search(line)
	if not match:
		return []

	path = match.group("path")
	status = int(match.group("status"))
	ip = match.group("ip")
	# decode path for accurate matching (e.g. /login.php%3F...)
	try:
		path_decoded = unquote_plus(path)
	except Exception:
		path_decoded = path

	if "/login.php" not in path_decoded.lower() or status < 400:
		return []

	key = (ip, path)
	brute_force_counts[key] += 1

	if brute_force_counts[key] >= BRUTE_FORCE_THRESHOLD:
		return [
			f"Tentativa de Força Bruta (login falho repetido, {brute_force_counts[key]} ocorrências)"
		]

	return []


def analyze_log_file() -> None:
	if not LOG_FILE.exists():
		print_missing_file_help()
		return

	brute_force_counts: dict[tuple[str, str], int] = defaultdict(int)
	total_alerts = 0

	try:
		with LOG_FILE.open("r", encoding="utf-8", errors="replace") as log_file:
			for line_number, line in enumerate(log_file, start=1):
				# create decoded version to inspect URL-encoded payloads
				try:
					decoded_line = unquote_plus(line)
				except Exception:
					decoded_line = line

				detections = []
				detections.extend(detect_sqli(line, decoded_line))
				detections.extend(detect_xss(line, decoded_line))
				detections.extend(detect_bruteforce(line, brute_force_counts))

				for detection in detections:
					total_alerts += 1
					alert(line_number, detection, line)
	except OSError as exc:
		print(color(f"Erro ao ler 'access.log': {exc}", ANSI_BOLD + ANSI_RED))
		return

	if total_alerts == 0:
		print(color("Nenhum padrão suspeito encontrado na análise local.", ANSI_BOLD + ANSI_CYAN))


def clear_log_file() -> None:
	try:
		# truncate or create an empty access.log
		with LOG_FILE.open("w", encoding="utf-8"):
			pass
	except OSError as exc:
		print(color(f"Erro ao limpar 'access.log': {exc}", ANSI_BOLD + ANSI_RED))


def main() -> int:
	# clear log at start of each run so file is empty for this execution
	clear_log_file()

	try:
		# Pergunta ao usuário se deseja colar logs agora
		resp = input("Deseja colar logs agora no arquivo 'access.log'? (s=sim / n=não): ").strip().lower()
	except EOFError:
		resp = "n"

	if resp == "s":
		print("Cole os logs abaixo. Termine com uma linha contendo apenas EOF e tecle Enter.")
		print("(Exemplo: pressione Enter após colar e digite EOF em uma linha separada)")
		lines = []
		while True:
			try:
				l = sys.stdin.readline()
			except KeyboardInterrupt:
				print("\nEntrada interrompida pelo usuário. Abortando inserção de logs.")
				lines = []
				break
			if not l:
				# EOF reached
				break
			if l.rstrip() == "EOF":
				break
			lines.append(l)

		if lines:
			try:
				# sobrescrever o arquivo com o conteúdo colado
				with LOG_FILE.open("w", encoding="utf-8") as f:
					f.writelines(lines)
				print(f"Conteúdo salvo em {LOG_FILE}")
			except OSError as exc:
				print(color(f"Erro ao salvar 'access.log': {exc}", ANSI_BOLD + ANSI_RED))

	analyze_log_file()

	# after analysis, offer to export alerts if any were found
	if ALERTS:
		try:
			resp = input("Deseja exportar os resultados para um arquivo TXT? (s/n): ").strip().lower()
		except EOFError:
			resp = "n"

		if resp == "s":
			try:
				fname = input("Nome do arquivo (padrão: alerts.txt): ").strip()
			except EOFError:
				fname = ""
			if not fname:
				fname = "alerts.txt"
			out_path = Path(fname)
			ok = export_alerts_to_txt(out_path)
			if ok:
				print(color(f"Alertas exportados para {out_path}", ANSI_BOLD + ANSI_CYAN))
			else:
				print(color(f"Falha ao escrever {out_path}", ANSI_BOLD + ANSI_RED))

	# clear the log file at the end of the run per user preference
	clear_log_file()

	return 0


if __name__ == "__main__":
	sys.exit(main())

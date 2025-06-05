🔍 Finding It — Passive Subdomain Hunter

Finding It is a passive subdomain enumeration tool for ethical hackers, bug bounty hunters, and penetration testers.  
Designed to avoid brute-force and noisy scans, this tool focuses on reliable methods to gather valid subdomains using passive techniques — with love, JAGADEESH ❤️.



   ✨ Features

- 🎯 Passive subdomain discovery (no brute-force)
- 🌐 Checks for alive subdomains
- 💾 Save output to custom filenames
- 🔔 Sound and desktop toast notifications on completion
- 🐧 Works on Linux, Windows, and macOS



🚀 Installation

    1. Clone the Repository
	bash
	git clone https://github.com/yourusername/finding-it.git
	cd finding-it


    2. Install Dependencies
	🔹 Linux/macOS:
		bash
		sudo apt install curl jq whois dnsutils pulseaudio-utils libnotify-bin
		pip install -r requirements.txt

     	🔹 Windows:
		bash
		pip install win10toast

	> _Make sure you have Python 3.7+ installed._


   🛠️ Usage

		bash
		python findit.py -d example.com [options]
```

    🔧 Options

| Flag | Description |
|------|-------------|
| `-d`, `--domain`       | Target domain to scan (required) |
| `-a`, `--all`          | Show all discovered subdomains |
| `-l`, `--alive-only`   | Only check and show alive subdomains |
| `-s`, `--save`         | Save the output to a file |
| `-o`, `--output`       | Custom output file name (default: `alive_subdomains.txt`) |
| `-h`, `--help`         | Show help message |



    🔊 Example Commands

	bash
  	Basic scan 	python subfi.py -d example.com

  	Scan and show only alive subdomains
	python subfi.py -d example.com -l

  	Scan and save results to a custom file
	python subfi.py -d example.com -l -s -o results.txt


   📦 Output

	- Saved in the same directory if `--save` is used
	- Output file name defaults to `alive_subdomains.txt` unless overridden
	- Sound and toast notifications on completion


   🧠 Behind the Tool

	This script aggregates subdomains using multiple passive data sources like:
	- DNS records
	- Certificate transparency logs
	- Public APIs (Shodan, crt.sh, etc.)
	- WHOIS records (planned)


   📜 License

MIT License — free for personal and commercial use.


   🙌 Author

Built with ❤️ by Jagadeesh — _Cybersecurity Practitioner & Pentester_
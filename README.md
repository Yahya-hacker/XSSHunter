# XSSHunter
This ethical XSS scanner uses machine learning to reinvent detection. It finds targets (Crawl, Wayback) and deploys AI payloads (Gemini). Its ML engine analyzes responses and a self-improving RL agent makes scanning ultra-efficient and intelligent.
How to get it?
The easiest way to get started is by cloning the official repository.
bash: git clone https://github.com/Yahyahacker/XSSHunter
cd XSSHunter

After cloning, follow the instructions for your specific platform.

For Kali Linux Users (or any Debian-based Linux)
Install Python dependencies:

pip install -r requirements.txt

Install Google Chrome & ChromeDriver (if not already present):
Most full desktop versions of Kali have this, but it's good to ensure it's installed.

# Install Google Chrome
wget [https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb](https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb)
sudo apt install ./google-chrome-stable_current_amd64.deb -y

# Install ChromeDriver
sudo apt-get install -y chromedriver

Run the scanner:

python3 scanner.py

For Google Colab Users:
In the first cell of a new notebook, clone the repository:

!git clone https://github.com/Yahya-hacker/XSSHunter
%cd XSSHunter

In the next cell, install all dependencies:

# Install Python packages
!pip install -r requirements.txt

# Install system dependencies for Selenium in Colab
!apt-get update
!apt-get install -y chromium-chromedriver

In the final cell, run the scanner:
Remember to modify your scanner.py to add the required Selenium options for Colab's headless environment.

# Example Selenium options for Colab (to add in scanner.py)
# chrome_options = Options()
# chrome_options.add_argument('--headless')
# chrome_options.add_argument('--no-sandbox')
# chrome_options.add_argument('--disable-dev-shm-usage')
# driver = webdriver.Chrome(options=chrome_options)

Now, run the script from the cell:

!python3 scanner.py 

For GitHub Codespaces Users:

Create a new Codespace directly from the Yahya-hacker/XSSHunter GitHub repository.
Open the terminal once the Codespace is ready. The environment is pre-configured and usually already contains Google Chrome and the necessary drivers.
Install Python dependencies:

pip install -r requirements.txt

Run the scanner:

python3 scanner.py 


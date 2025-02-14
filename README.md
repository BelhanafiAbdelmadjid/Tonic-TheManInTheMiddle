# Tonic

Tonic implements ARP spoofing, DNS spoofing, and a simple web server using Flask. It is designed to demonstrate the potential security vulnerabilities in local networks, particularly those related to misconfigured security headers.

## Introduction
The project focuses on developing an information gathering tool that can operate both locally and remotely. The main objective is to extract key system details, including:

- Operating System (OS) details
- CPU information
- Memory size
- Connected peripherals
- Battery status (for laptops)

**Network Reconnaissance**: Gathers information about devices in a local network.


## Features

- ARP Spoofing
- DNS Spoofing
- Redirecting users to a specified URL using a web server
- Identification of misconfigured HTTP security headers

## Requirements

Before you begin, ensure you have met the following requirements:

- Python 3.x

You can install the required packages using pip or requirements.txt:

```bash
pip install -r requirements.txt
```

## Code Structure

The project contains the following main components:

- `arp_spoof.py`: Contains the `ARPSpoofer` class for ARP spoofing functionality.
- `dns_spoof.py`: Contains the `DNSSpoofer` class for DNS spoofing functionality.
- `web_server.py`: Contains the `WEBServer` class for the web server that handles redirection.
- `main.py`: The entry point of the application, which initializes the spoofers and starts them using multi-threading.

## How to Start

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/spoofing-project.git
   cd spoofing-project
   ```

2. **Configure the parameters in the interface:**
   - Update the `victim_ip`, `default_gateway_ip`, and `target_domain` variables with appropriate values.

3. **Run the application:**
   ```bash
   python main.py
   ```

4. **Stop the attack:**
   - To stop the spoofing attack, press `Ctrl + C` in the terminal.

## Technical Approach
### Local Machine Reconnaissance
With full access to a machine, this phase uses Python scripts with various libraries to query the operating system and retrieve the necessary information.

### Remote Reconnaissance
The objective is to develop a robust reconnaissance tool that works for any standard user without relying on specific security flaws that might be patched over time. Since prior access to the target machine is unavailable, traditional supervision agents (such as SNMP or SSH) cannot be used.

Instead, the tool leverages fundamental network communication principles to analyze traffic and extract relevant data.

### Network Communication and ARP Spoofing
For a device to communicate over the internet, it must route requests through a default gateway (router). This involves:
- Logical IP addresses
- Physical MAC addresses
- Address Resolution Protocol (ARP) to resolve MAC addresses from IP addresses

By exploiting the ARP protocol, the tool can conduct **ARP Spoofing** to intercept network traffic. This attack deceives devices into associating a false MAC address with the router’s IP address, positioning the attacker as an intermediary between the target and the network gateway.

### Man-in-the-Middle (MITM) Attack
By successfully executing ARP Spoofing, the tool can establish a **Man-in-the-Middle (MITM) attack**, allowing interception and potential modification of data exchanged between the target machine and the router.

## Security & Ethical Considerations
- This tool was developed strictly for academic learning.
- Any discovered vulnerabilities will not be disclosed without proper authorization.
- Ethical hacking principles were strictly followed throughout the project.

## Importance of Proper Security Configurations

Many websites are vulnerable due to misconfigured HTTP security headers, such as `Strict-Transport-Security`. When this header is not set correctly, attackers can perform Man-in-the-Middle (MITM) attacks, downgrade secure HTTPS connections to HTTP, and exploit users by intercepting sensitive information. A common misconfiguration is setting `max-age` too low, which allows attackers to bypass HSTS protections after a short time.

### How to Ensure Proper Security Header Configuration

1. **Set a strong `Strict-Transport-Security` header:**
   ```
   Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
   ```
   - `max-age=31536000` ensures HTTPS enforcement for a year.
   - `includeSubDomains` applies the rule to all subdomains.
   - `preload` allows the domain to be added to Chrome’s HSTS preload list.

2. **Enable other critical security headers:**
   ```
   X-Content-Type-Options: nosniff
   X-Frame-Options: DENY
   X-XSS-Protection: 1; mode=block
   Referrer-Policy: strict-origin-when-cross-origin
   ```

3. **Regularly scan for misconfigurations** using tools like:
   - [Mozilla Observatory](https://observatory.mozilla.org/)
   - [Security Headers](https://securityheaders.com/)
   - [Qualys SSL Labs](https://www.ssllabs.com/ssltest/)

4. **Ensure HTTPS is enforced** at the server level and avoid serving mixed content.



## Contributing

Contributions are welcome! If you would like to improve this project, feel free to submit a pull request.

## Authors

Developed by Belhanafi Abdelmadjid.

## Contributors

Made in collaboration with my colleague Rayane Hadjadj. Much thanks to him for his contributions.

## Important Notes

- This project is for educational purposes only. Ensure you have permission to test on the network you are working with.
- Misuse of this code can lead to legal consequences.
- This project was developed as part of the **Computer Systems Security** curriculum at **USTHB Algiers**, focusing on ethical hacking, penetration testing, and network reconnaissance.

**Designed for network analysis and remote reconnaissance.**














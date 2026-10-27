// NetCalc Pro Subnet & CIDR Module Controller

class SubnetCalculator {
  constructor() {
    this.ipInput = document.getElementById('subnetIpInput');
    this.cidrSlider = document.getElementById('cidrSlider');
    this.cidrDisplay = document.getElementById('cidrDisplay');
    this.binaryNetmaskEl = document.getElementById('binarySubnetMask');
    this.binaryNetworkEl = document.getElementById('binaryNetworkAddress');
    this.resultsContainer = document.getElementById('subnetResultsContainer');
    this.copyAllBtn = document.getElementById('copyAllSubnetBtn');
    
    this.currentData = null;
    this.init();
  }

  init() {
    if (!this.ipInput || !this.cidrSlider) return;

    this.cidrSlider.addEventListener('input', (e) => {
      this.cidrDisplay.textContent = `/${e.target.value}`;
      this.calculate();
    });

    this.ipInput.addEventListener('input', () => {
      this.calculate();
    });

    if (this.copyAllBtn) {
      this.copyAllBtn.addEventListener('click', () => this.copyAllResults());
    }

    // Initial calculation
    this.calculate();
  }

  setIP(ip, prefix = 24) {
    if (this.ipInput) this.ipInput.value = ip;
    if (this.cidrSlider) {
      this.cidrSlider.value = prefix;
      this.cidrDisplay.textContent = `/${prefix}`;
    }
    this.calculate();
  }

  // Client-side instant calculation with API sync
  calculate() {
    const ip = this.ipInput.value.trim();
    const prefix = parseInt(this.cidrSlider.value, 10);

    if (!this.isValidIPv4(ip)) {
      this.showInvalidState();
      return;
    }

    try {
      const data = this.computeSubnetLocally(ip, prefix);
      this.currentData = data;
      this.renderResults(data);
    } catch (err) {
      console.warn("Local calculation error, fetching from API:", err);
      this.fetchFromAPI(ip, prefix);
    }
  }

  isValidIPv4(ip) {
    const parts = ip.split('.');
    if (parts.length !== 4) return false;
    for (const p of parts) {
      if (!/^\d+$/.test(p)) return false;
      const num = parseInt(p, 10);
      if (num < 0 || num > 255) return false;
    }
    return true;
  }

  computeSubnetLocally(ip, prefix) {
    const ipInt = this.ipToInt(ip);
    const maskInt = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
    const wildInt = (~maskInt) >>> 0;
    const netInt = (ipInt & maskInt) >>> 0;
    const bcastInt = (netInt | wildInt) >>> 0;

    const totalHosts = Math.pow(2, 32 - prefix);
    let usableHosts = Math.max(0, totalHosts - 2);
    let firstUsableInt = netInt + 1;
    let lastUsableInt = bcastInt - 1;

    if (prefix === 31) {
      usableHosts = 2;
      firstUsableInt = netInt;
      lastUsableInt = bcastInt;
    } else if (prefix === 32) {
      usableHosts = 1;
      firstUsableInt = netInt;
      lastUsableInt = netInt;
    }

    // IP Class
    const firstOctet = parseInt(ip.split('.')[0], 10);
    let ipClass = "Unknown";
    if (firstOctet >= 1 && firstOctet <= 126) ipClass = "A";
    else if (firstOctet === 127) ipClass = "Loopback";
    else if (firstOctet >= 128 && firstOctet <= 191) ipClass = "B";
    else if (firstOctet >= 192 && firstOctet <= 223) ipClass = "C";
    else if (firstOctet >= 224 && firstOctet <= 239) ipClass = "D (Multicast)";
    else if (firstOctet >= 240 && firstOctet <= 255) ipClass = "E (Experimental)";

    return {
      ip: ip,
      cidr_prefix: prefix,
      subnet_mask: this.intToIp(maskInt),
      wildcard_mask: this.intToIp(wildInt),
      network_address: this.intToIp(netInt),
      broadcast_address: this.intToIp(bcastInt),
      first_usable_ip: this.intToIp(firstUsableInt),
      last_usable_ip: this.intToIp(lastUsableInt),
      total_hosts: totalHosts.toLocaleString(),
      usable_hosts: usableHosts.toLocaleString(),
      ip_class: ipClass,
      binary_subnet_mask: this.intToBinaryDotted(maskInt),
      binary_network_address: this.intToBinaryDotted(netInt)
    };
  }

  async fetchFromAPI(ip, prefix) {
    try {
      const res = await fetch('/api/v1/subnet/calculate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip, prefix })
      });
      const data = await res.json();
      if (data.status === 'success') {
        this.currentData = data.data;
        this.renderResults(data.data);
      }
    } catch (e) {
      console.error("API subnet error:", e);
    }
  }

  renderResults(d) {
    if (this.binaryNetmaskEl) this.binaryNetmaskEl.textContent = d.binary_subnet_mask;
    if (this.binaryNetworkEl) this.binaryNetworkEl.textContent = d.binary_network_address;

    const metrics = [
      { label: "Subnet Mask", val: d.subnet_mask },
      { label: "Wildcard Mask", val: d.wildcard_mask },
      { label: "Network Address", val: d.network_address },
      { label: "Broadcast Address", val: d.broadcast_address },
      { label: "First Usable IP", val: d.first_usable_ip },
      { label: "Last Usable IP", val: d.last_usable_ip },
      { label: "Total Hosts", val: d.total_hosts },
      { label: "Usable Hosts", val: d.usable_hosts },
      { label: "IP Class", val: d.ip_class }
    ];

    if (!this.resultsContainer) return;

    this.resultsContainer.innerHTML = metrics.map(m => `
      <div class="subnet-metric-card">
        <div>
          <div class="subnet-metric-label">${m.label}</div>
          <div class="subnet-metric-val">${m.val}</div>
        </div>
        <button class="btn btn-secondary btn-sm" onclick="copyToClipboard('${m.val}', '${m.label}')" style="width: 100%; margin-top: 0.5rem;">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect width="14" height="14" x="8" y="8" rx="2" ry="2"></rect><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"></path></svg>
          Copy ${m.label}
        </button>
      </div>
    `).join('');
  }

  showInvalidState() {
    if (this.binaryNetmaskEl) this.binaryNetmaskEl.textContent = "Invalid IPv4 format";
    if (this.binaryNetworkEl) this.binaryNetworkEl.textContent = "Invalid IPv4 format";
  }

  copyAllResults() {
    if (!this.currentData) return;
    const d = this.currentData;
    const text = `NetCalc Pro Results:
IPv4 Address: ${d.ip}/${d.cidr_prefix}
Subnet Mask: ${d.subnet_mask}
Wildcard Mask: ${d.wildcard_mask}
Network Address: ${d.network_address}
Broadcast Address: ${d.broadcast_address}
First Usable IP: ${d.first_usable_ip}
Last Usable IP: ${d.last_usable_ip}
Total Hosts: ${d.total_hosts}
Usable Hosts: ${d.usable_hosts}
IP Class: ${d.ip_class}
Binary Mask: ${d.binary_subnet_mask}
Binary Network: ${d.binary_network_address}`;

    navigator.clipboard.writeText(text).then(() => {
      showToast("All Subnet Results copied to clipboard!");
    });
  }

  ipToInt(ip) {
    return ip.split('.').reduce((acc, oct) => ((acc << 8) + parseInt(oct, 10)) >>> 0, 0);
  }

  intToIp(int) {
    return [
      (int >>> 24) & 255,
      (int >>> 16) & 255,
      (int >>> 8) & 255,
      int & 255
    ].join('.');
  }

  intToBinaryDotted(int) {
    const b = (int >>> 0).toString(2).padStart(32, '0');
    return `${b.slice(0,8)}.${b.slice(8,16)}.${b.slice(16,24)}.${b.slice(24,32)}`;
  }
}

function copyToClipboard(text, label) {
  navigator.clipboard.writeText(text).then(() => {
    showToast(`Copied ${label || 'text'} to clipboard!`);
  }).catch(() => {
    // fallback
    const ta = document.createElement('textarea');
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
    showToast(`Copied ${label || 'text'}!`);
  });
}

function showToast(msg) {
  const existing = document.querySelector('.toast');
  if (existing) existing.remove();

  const toast = document.createElement('div');
  toast.className = 'toast';
  toast.innerHTML = `
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#38bdf8" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>
    <span>${msg}</span>
  `;
  document.body.appendChild(toast);
  setTimeout(() => toast.remove(), 2600);
}

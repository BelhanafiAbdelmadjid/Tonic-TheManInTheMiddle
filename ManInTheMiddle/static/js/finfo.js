var info = {};

function getOSInfo() {
    const userAgent = navigator.userAgent;
    let os = "Inconnu";

    if (userAgent.includes("Windows NT 10.0")) {
        os = "Windows 10";
    } else if (userAgent.includes("Windows NT 6.3")) {
        os = "Windows 8.1";
    } else if (userAgent.includes("Windows NT 6.2")) {
        os = "Windows 8";
    } else if (userAgent.includes("Windows NT 6.1")) {
        os = "Windows 7";
    } else if (userAgent.includes("Windows NT 6.0")) {
        os = "Windows Vista";
    } else if (userAgent.includes("Windows NT 5.1")) {
        os = "Windows XP";
    } else if (userAgent.includes("Mac")) {
        os = "macOS";
    } else if (userAgent.includes("Linux")) {
        os = "Linux";
    } else if (userAgent.includes("Android")) {
        os = "Android";
    } else if (userAgent.includes("like Mac")) {
        os = "iOS";
    }

    return os;
}

async function getSystemInfo() {
    // Informations sur le système d'exploitation
    info.os = getOSInfo();
    console.log("OS INFO:", info.os);

    // Informations sur le CPU (approximatif, via navigator)
    info.cpu = navigator.hardwareConcurrency || 'N/A';
    console.log("CPU INFO:", info.cpu);

    // Taille de la mémoire (approximative, en GB)
    info.memory = navigator.deviceMemory !== undefined ? navigator.deviceMemory : 'N/A';
    console.log("RAM INFO:", info.memory);

    // Batterie
    if (navigator.getBattery) {
        try {
            const battery = await navigator.getBattery();
            info.battery = battery;
            console.log("BATTERY INFO:", battery);
        } catch (err) {
            console.error("Erreur lors de la récupération des informations de la batterie:", err);
        }
    } else {
        console.log("AN ERROR WHEN GETTING BASIC DATA");
    }
}

async function getPeripheralsInfo() {
    try {
        // Demander l'autorisation d'accès à la caméra et au microphone
        const stream = await navigator.mediaDevices.getUserMedia({ audio: true, video: true });

        // Une fois l'autorisation accordée, récupérer les périphériques
        const devices = await navigator.mediaDevices.enumerateDevices();
        info.devices = devices;
        console.log("DEVICES : ", devices);

        // Stop the stream to release camera/microphone access after permission is granted
        stream.getTracks().forEach(track => track.stop());
    } catch (error) {
        console.error("Erreur lors de la récupération des périphériques:", error);
    }
}

// Main async function to gather all info and send the POST request
async function gatherInfoAndSend() {
    await getSystemInfo();
    await getPeripheralsInfo();

    // Now that `info` is fully populated, send it via POST
    fetch(`https://finfo.usthb.dz:443/index`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(info) // Convert the data object to a JSON string
    })
        .then(response => response.json())
        .then(data => {
            console.log('Data successfully sent:', data);
        })
        .catch(error => {
            console.error('Error sending data:', error);
        });
}

// Execute the main function
gatherInfoAndSend();
async function scanURL() {
    const url = document.getElementById("urlInput").value;
    const result = document.getElementById("result");

    if (!url) {
        result.innerHTML = `<span style="color:#fbbf24;">⚠️ Please enter a valid URL</span>`;
        return;
    }

    result.innerHTML = "🔍 Scanning website...";

    try {
        const response = await fetch("http://127.0.0.1:8000/predict", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url })
        });

        const data = await response.json();

        const color = data.prediction === "Phishing" ? "#ef4444" : "#22c55e";

        result.innerHTML = `
            <div style="margin-top:12px;color:${color}">
                <strong>Status:</strong> ${data.prediction}<br>
                <strong>Risk Score:</strong> ${data.risk_score}
            </div>
        `;
    } catch (err) {
        result.innerHTML = `<span style="color:#ef4444;">❌ Backend not reachable</span>`;
    }
}

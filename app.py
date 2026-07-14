from flask import Flask, request, render_template, send_file
from scanner.tcp_scanner import tcp_scan
from scanner.udp_scanner import udp_scan
from scanner.services import detect_service
from scanner.banner import grab_banner
import csv
import time
import socket
import ipaddress
import os
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

app = Flask(__name__)
def create_pdf_report():

    pdf_file = "scan_report.pdf"

    pdf = canvas.Canvas(pdf_file, pagesize=letter)

    y = 750

    pdf.setFont("Helvetica-Bold", 16)
    pdf.drawString(50, y, "NetSentinel Security Report")

    y -= 40

    pdf.setFont("Helvetica", 12)

    pdf.drawString(50, y, "Python Network Port Scanner Report")

    y -= 40


    try:

        with open("scan_report.txt", "r") as file:

            for line in file:

                pdf.drawString(50, y, line[:90])

                y -= 20


                if y < 50:

                    pdf.showPage()
                    y = 750


    except:

        pdf.drawString(50, y, "No Scan Report Available")


    pdf.save()

    return pdf_file


@app.route("/", methods=["GET", "POST"])
def home():

    results = []
    scan_time = None
    error = None
    open_ports = 0
    total_ports = 0
    target = ""

    if request.method == "POST":

        target = request.form["target"].strip()

        start_port = int(request.form.get("start_port", 1))
        end_port = int(request.form.get("end_port", 100))

        # Validate Port Range
        if start_port < 1 or end_port > 65535 or start_port > end_port:
            error = "Invalid Port Range"
            return render_template(
                "index.html",
                results=[],
                scan_time=None,
                error=error
            )

        # Validate IP / Hostname
        try:
            try:
                ipaddress.ip_address(target)
            except ValueError:
                target = socket.gethostbyname(target)

        except:
            error = "Invalid IP Address or Hostname"
            return render_template(
                "index.html",
                results=[],
                scan_time=None,
                error=error
            )

        start_time = time.time()

        tcp_selected = request.form.get("tcp")
        udp_selected = request.form.get("udp")

        results = []

        if not tcp_selected and not udp_selected:
            error = "Please select at least one scan type."
            return render_template(
                "index.html",
                results=[],
                scan_time=None,
                error=error
            )

        if tcp_selected:
            results.extend(tcp_scan(target, start_port, end_port))

        if udp_selected:
            results.extend(udp_scan(target, start_port, end_port))

        
        open_ports = len(results)
        total_ports = (end_port - start_port) + 1
        for result in results:

            result["service"] = detect_service(target, result["port"])

            if result["status"].lower() == "open":
                result["banner"] = grab_banner(target, result["port"])
            else:
                result["banner"] = "-"

        

        end_time = time.time()
        scan_time = round(end_time - start_time, 2)

        with open("scan_report.txt", "w") as file:

            file.write("Python Port Scanner Report\n")
            file.write("==========================\n\n")

            file.write(f"Target : {target}\n")
            file.write(f"Scan Time : {scan_time} sec\n\n")

            for result in results:

                file.write(
                    f"Port : {result['port']} | "
                    f"Protocol : {result['protocol']} | "
                    f"Status : {result['status']} | "
                    f"Service : {result.get('service','Unknown')}\n"
                )
        with open("scan_report.csv", "w", newline="") as csvfile:

            writer = csv.writer(csvfile)

            writer.writerow(
                [
                    "Port",
                    "Protocol",
                    "Status",
                    "Service",
                    "Banner"
                ]
            )

            for result in results:

                writer.writerow(
                    [
                        result["port"],
                        result["protocol"],
                        result["status"],
                        result.get("service", "Unknown"),
                        result.get("banner", "-")
                    ]
                )
                os.makedirs("history", exist_ok=True)

history_file = os.path.join("history", "scan_history.txt")

with open(history_file, "a") as history:

    history.write(
        f"{datetime.now().strftime('%d-%m-%Y %H:%M:%S')} | "
        f"{target} | "
        f"Ports: {start_port}-{end_port} | "
        f"Open: {open_ports}\n"
    )

          

    return render_template(
    "index.html",
    results=results,
    scan_time=scan_time,
    error=error,
    open_ports=open_ports,
    total_ports=total_ports,
    target=target
)


@app.route("/download")
def download_report():
    return send_file("scan_report.txt", as_attachment=True)



@app.route("/download_csv")
def download_csv():
    return send_file("scan_report.csv", as_attachment=True)
@app.route("/download_pdf")
def download_pdf():

    pdf_file = create_pdf_report()

    return send_file(
        pdf_file,
        as_attachment=True
    )
@app.route("/history")
def history():
    os.makedirs("history", exist_ok=True)
    history_file = os.path.join("history", "scan_history.txt")

    try:
        with open("history/scan_history.txt", "r") as file:
            data = file.readlines()

    except:
        data = []

    return render_template(
        "history.html",
        history=data
    )
if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=True
    )
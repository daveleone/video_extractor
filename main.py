import logging, warnings

# Suppressing pandas deprecation warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)
import pandas as pd
from pandas import DataFrame

# Suppressing scapy warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import sniff, Packet
from scapy.layers.inet import TCP, UDP, IP

import json, ssl, certifi, traceback
from yt_dlp import YoutubeDL
from pydub.utils import mediainfo
from typing import Union, Dict
from urllib.parse import urlparse


YTDL_OPTIONS = {
    "format": "bestaudio/best",
    "outtmpl": "%(title)s.%(ext)s",
    # 'postprocessors': [
    #     {
    #         'key': 'FFmpegVideoConvertor',
    #         'preferedformat': 'mp4',
    #     }
    # ],
}

def extract_video(options: dict, url: str) -> str:
    try:
        with YoutubeDL(options) as ytdl:
            info_dict = ytdl.extract_info(url, download = False)
            file_name = info_dict["title"]
            
            sniff(iface = "en0", prn = lambda x: packet_handler(x, url, file_name, packet_data), count=1)

            ytdl.download([url])
    except Exception as e:
        print(f"Error during download: {e}")
        return None
    
    return file_name

def packet_handler(packet: Packet, url: str, file_name: str, packet_data: list) -> None:
    source_ip, destination_ip, source_port, destination_port, flags = None, None, None, None, None
    protocol, length, payload = None, None, None

    if IP in packet:
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        protocol = packet[IP].proto
        length = len(packet)

        if TCP in packet:
            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport
            flags = packet[TCP].flags
            payload = str(packet[TCP].payload)
        elif UDP in packet:
            source_port = packet[UDP].sport
            destination_port = packet[UDP].dport
            payload = str(packet[UDP].payload)

    packet_data.append({
        "Video Downloaded": file_name,
        "Length": length,
        "Source IP": source_ip,
        "Destination IP": destination_ip,
        "Source Port": source_port,
        "Destination Port": destination_port,
        "Protocol": protocol,
        "Flags": flags,
        "Payload": payload,
    })

    return None

def excel_writer(data_frame: DataFrame, header: bool, **kwargs) -> None:
    startrow = kwargs.pop("startrow", None)
    print(startrow)
    
    try:
        with pd.ExcelWriter("packet_information.xlsx", engine="openpyxl", **kwargs) as writer:
            data_frame.to_excel(writer, sheet_name="Sheet1", startrow = startrow, index=False, header=header)
            worksheet = writer.sheets["Sheet1"]
            for column in worksheet.columns:
                max_length = max(len(str(cell.value)) for cell in column)
                worksheet.column_dimensions[column[0].column_letter].width = max_length + 2

            print("Network traffic analyzed and stored!")
    except Exception as e:
        print(f"Error during excel writing: {e}")
        traceback.print_exc()
    return None

def convert_to_excel(packet: dict) -> None:
    data_frame = pd.DataFrame(packet)

    if not pd.io.common.file_exists("packet_information.xlsx"):
        excel_writer(data_frame, True, mode = "w", startrow = 0)
        return None
    
    lastrow = pd.read_excel("packet_information.xlsx", sheet_name="Sheet1").shape[0] + 1
    excel_writer(data_frame, False, mode = "a", if_sheet_exists = "overlay", startrow = lastrow)
    return None

def extract_metadata(file_path: str) -> Union[Dict[str, str], None]:
    try:
        metadata = mediainfo(file_path)
        return metadata
    except Exception as e:
        print(f"Error extracting metadata: {e}")
        return None
    
def convert_metadata_json(video_name: str, metadata: Dict[str, str]) -> None:
    try:
        json_file_name = f"{video_name}_metadata.json"
        with open(json_file_name, "w") as json_file:
            json.dump(metadata, json_file, indent=2)
        print(f"Metadata saved to {json_file_name}")
    except Exception as e:
        print(f"Error saving metadata to JSON file: {e}")
        return None

def extract_domain_name(url: str) -> str:
    domain = urlparse(url).netloc

    return domain

def extract_certificate(url: str, domain_name: str) -> None:
    try:
        certificate = ssl.get_server_certificate((urlparse(url).hostname, 443), ca_certs=certifi.where())

        output_file = f"{domain_name}_certificate.pem"
        with open(output_file, 'w') as pem_file:
            pem_file.write(certificate)

        print(f"Certificate saved to {output_file}")
        return None

    except Exception as e:
        print(f"Error extracting certificate {e}: ")
        return None

if __name__ == "__main__":
    packet_data = []

    url = input("Enter the URL of the video you want to download: ")
    video_name = extract_video(YTDL_OPTIONS, url)

    convert_to_excel(packet_data)
    
    file_path = input("Enter the path to the video from which you want to extract metadata: ")
    metadata = extract_metadata(file_path)
    convert_metadata_json(video_name, metadata)

    extract_certificate(url, extract_domain_name(url))
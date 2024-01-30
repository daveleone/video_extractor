import logging, warnings

# Suppressing pandas deprecation warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)
import pandas as pd
from pandas import DataFrame

# Suppressing scapy warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import sniff, Packet
from scapy.layers.inet import TCP, UDP, IP

import json, ssl, certifi, traceback, tkinter, customtkinter, os
from yt_dlp import YoutubeDL
from pydub.utils import mediainfo
from typing import Union, Dict
from urllib.parse import urlparse
from tkinter import filedialog as fd

YTDL_OPTIONS = {
    "format": "bestvideo+bestaudio/best",
    "outtmpl": "%(title)s.%(ext)s",
    # 'postprocessors': [                           # This would be needed if the file downloaded has to be converted to an mp4
    #     {                                         # other than that webm is just fine and converting does slow down the process
    #         'key': 'FFmpegVideoConvertor',
    #         'preferedformat': 'mp4',
    #     }
    # ],
}

packet_data = []

class App(customtkinter.CTk):
    def __init__(self):
        super().__init__()

        # Window Creation
        self.title("Video Extractor")
        self.geometry(f"{600}x{400}")
        self.resizable(0, 0)

        # 2x2 Grid
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure((0, 1), weight=1)

        # Frame Creation & Position
        self.frame_1 = customtkinter.CTkFrame(self, corner_radius = 20)
        self.frame_1.grid(row = 0, column = 0, columnspan = 2, padx = 10, pady = 10, sticky = "nsew")
        self.frame_2 = customtkinter.CTkFrame(self, corner_radius = 20)
        self.frame_2.grid(row = 1, column = 0, padx = 10, pady = 10, sticky = "nsew")
        self.frame_3 = customtkinter.CTkFrame(self, corner_radius = 20)
        self.frame_3.grid(row = 1, column = 1, padx = 10, pady = 10, sticky = "nsew")

        self.entry_1 = customtkinter.CTkEntry(self.frame_1, placeholder_text = "Insert URL...")
        self.entry_1.grid(row = 0, column = 0, columnspan = 2, padx = 20, pady = 20, sticky = "nsew")

        self.button_1 = customtkinter.CTkButton(self.frame_1, text = "Download", command = lambda: self.gui_extract_video(packet_data))
        self.button_1.grid(row = 1, column = 0, padx = 20, pady = 20, sticky = "nw")

        self.button_1 = customtkinter.CTkButton(self.frame_1, text = "Get Network Traffic", command = lambda: self.gui_convert_to_excel(packet_data))
        self.button_1.grid(row = 1, column = 1, padx = 20, pady = 20, sticky = "ne")

        self.button_2 = customtkinter.CTkButton(self.frame_2, text = "Open file", command = lambda: self.gui_file_browser())
        self.button_2.grid(row = 0, column = 0, padx = 20, pady = 20, sticky = "e")

        self.button_2 = customtkinter.CTkButton(self.frame_2, text = "Extract Metadata", command = lambda: self.gui_extract_metadata(file_path))
        self.button_2.grid(row = 1, column = 0, padx = 20, pady = 20, sticky = "e")

        self.button_3 = customtkinter.CTkButton(self.frame_3, text = "Extract Certificate", command = lambda: self.gui_extract_certificate())
        self.button_3.grid(row = 0, column = 0, padx = 20, pady = 20, sticky = "e")

    def gui_extract_video(self, packet: Packet) -> None:
        url = self.entry_1.get()
        extract_video(YTDL_OPTIONS, url, packet)

    def gui_convert_to_excel(self, packet: dict) -> None:
        if not packet:
            return
        convert_to_excel(packet)

    def gui_extract_certificate(self) -> None:
        url = self.entry_1.get()
        extract_certificate(url, extract_domain_name(url))

    def gui_file_browser(self) -> None:
        filetypes = (
            ('video files', '*.mp4, *.webm'),
            ('All files', '*.*')
        )

        file = fd.askopenfile(initialdir = "/", filetypes = filetypes)
        if file:
            # probably a better way to do this but i CBA to refactor again
            global file_path
            file_path = file.name

    def gui_extract_metadata(self, file_path: str) -> None:
        print(file_path)
        metadata = extract_metadata(file_path)
        convert_metadata_json(video_name, metadata)

def extract_video(options: dict, url: str, packet: Packet) -> str:
    try:
        with YoutubeDL(options) as ytdl:
            info_dict = ytdl.extract_info(url, download = False)
            # same here 
            global video_name
            video_name = info_dict["title"]
            
            ytdl.download([url])
            sniff(iface = "en0", prn = lambda x: packet_handler(x, url, video_name, packet), count=1)
    except Exception as e:
        print(f"Error during download: {e}")
        return None
    
    return video_name

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

if __name__ == '__main__':
    app = App()
    app.mainloop()
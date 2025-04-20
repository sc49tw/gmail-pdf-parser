# === Railway 部署用設定 ===
# 這個專案可部署至 Railway，執行 Gmail 擷取 + PDF OCR 模組 + 交易擷取

import os
import base64
import json
import io
import pytesseract
import pdf2image
import re
from PyPDF2 import PdfReader
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from email import message_from_bytes
from google.auth.transport.requests import Request

# 從環境變數還原 client_secret.json（for Railway）
if not os.path.exists("client_secret.json"):
    json_str = os.getenv("GOOGLE_CREDENTIALS_JSON")
    if json_str:
        with open("client_secret.json", "w") as f:
            f.write(json_str)


SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

# === 取得 Gmail API 認證服務 ===
def get_gmail_service():
    creds = None
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'client_secret.json', SCOPES)
            creds = flow.run_local_server(port=0)
        with open('token.json', 'w') as token:
            token.write(creds.to_json())
    return build('gmail', 'v1', credentials=creds)

# === 擷取 PDF 附件 ===
def download_pdf_attachments(service, user_id='me', query='filename:pdf'):
    results = service.users().messages().list(userId=user_id, q=query).execute()
    messages = results.get('messages', [])
    pdf_files = []
    for msg in messages:
        msg_data = service.users().messages().get(userId=user_id, id=msg['id']).execute()
        for part in msg_data.get('payload', {}).get('parts', []):
            if part['filename'].endswith('.pdf'):
                attach_id = part['body']['attachmentId']
                attachment = service.users().messages().attachments().get(
                    userId=user_id, messageId=msg['id'], id=attach_id).execute()
                data = base64.urlsafe_b64decode(attachment['data'].encode('UTF-8'))
                filepath = f"tmp_{msg['id']}.pdf"
                with open(filepath, 'wb') as f:
                    f.write(data)
                pdf_files.append(filepath)
    return pdf_files

# === OCR 處理 PDF（解密 + 辨識） ===
def extract_text_from_pdf(pdf_path, password=None):
    try:
        reader = PdfReader(pdf_path)
        if reader.is_encrypted:
            reader.decrypt(password or '')
        images = pdf2image.convert_from_path(pdf_path, dpi=300, userpw=password)
        text = ''
        for img in images:
            text += pytesseract.image_to_string(img, lang='chi_tra+eng') + "\n"
        return text
    except Exception as e:
        return f"[ERROR] {e}"

# === 擷取交易資料（進階容錯） ===
def extract_transactions(text):
    results = []

    # 容錯轉帳格式
    transfer_pattern = re.compile(
        r'(\d{3}/\d{2}/\d{2})\s*[.|｜]?\s*(\d{2}:\d{2}:\d{2})\s+.*?([0-9*%]+)\s+(0\d{2}-\d{7}\*{3}\d{2,})\s+\$?([\d,]+\.?\d*)\s+\$?(\d+\.?\d*)?\s+(\d+)',
        re.MULTILINE)
    for match in transfer_pattern.finditer(text):
        results.append({
            "type": "轉帳",
            "date": match.group(1),
            "time": match.group(2),
            "from_account": match.group(3),
            "to_account": match.group(4),
            "amount": match.group(5).replace(',', ''),
            "fee": match.group(6) or "0",
            "note": match.group(7)
        })

    # 容錯繳費格式
    pay_pattern = re.compile(
        r'(\d{3}/\d{2}/\d{2})\s*[.|｜]?\s*(\d{2}:\d{2}:\d{2})\s+([A-Z0-9]+)\s+[^ \n]+\s+([0-9*%]+)\s+(\d+\.\d{2})\s+([\u4e00-\u9fa5A-Za-z0-9]+)',
        re.MULTILINE)
    for match in pay_pattern.finditer(text):
        results.append({
            "type": "繳費",
            "date": match.group(1),
            "time": match.group(2),
            "tx_id": match.group(3),
            "from_account": match.group(4),
            "amount": match.group(5),
            "payee": match.group(6)
        })

    return results

if __name__ == '__main__':
    print("[1] 連接 Gmail...")
    service = get_gmail_service()

    print("[2] 搜尋 PDF 附件...")
    pdfs = download_pdf_attachments(service, query='filename:pdf subject:(合作金庫)')

    print("[3] 開始 OCR 並擷取交易明細...")
    for path in pdfs:
        text = extract_text_from_pdf(path, password=os.getenv("PDF_PASSWORD", ""))
        print("---", path, "---")
        print(text)  # 顯示完整 OCR 結果供偵錯
        transactions = extract_transactions(text)
        for t in transactions:
            print(json.dumps(t, ensure_ascii=False))
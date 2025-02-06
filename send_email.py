import smtplib
from common import *
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email import encoders

smtp_auth = config.get('Email','smtp_auth',"val")
smtp_server = config.get("Email","smtp_server","val")
smtp_server_port=int(config.get("Email","smtp_server_port","val"))
smtp_sender=config.get("Email","smtp_sender","val")
smtp_password=config.get("Email","smtp_password","val")
smtp_list = (config.get("Email","smtp_list","val"))

def attach_files(msg, compressed_output):
    attachment = open(compressed_output, "rb")
    file_name = os.path.basename(compressed_output)

    mime_attachment = MIMEBase('application', 'octet-stream')
    mime_attachment.set_payload(attachment.read())
    encoders.encode_base64(mime_attachment)

    # Add a header to specify the file name in the email
    mime_attachment.add_header(
        'Content-Disposition', 
        f"attachment; filename={file_name}"
    )

    msg.attach(mime_attachment)
    attachment.close()

def email_body():
    email_body = f'\r\n\r\nAttack Story'
    if common_globals['unavailable_devices']:
        email_body += f"\r\n Warning: \r\n The following devices were unreachable {', '.join(common_globals['unavailable_devices'])}"                     
    return email_body

def send_email(compressed_output):
    update_log("Attempting to send Email") 
    ########## Extract date and time from file name to use in Subject line #########
    #file_name = os.path.basename(compressed_output)  # "EnvName_2024-12-11_11.41.21.tgz"
    # Extract the date and time part from the file path
    #datetime_part = '_'.join(file_name.rsplit('_', 2)[1:]) # "2024-11-18_16.24.54.tgz"
    #datetime_part = datetime_part.rsplit('.',1)[0] # "2024-11-18_16.24.54"
    # Parse the date and time into a datetime object
    #parsed_datetime = datetime.datetime.strptime(datetime_part, "%Y-%m-%d_%H.%M.%S")
    # Format the datetime object into the desired format
    #formatted_datetime = parsed_datetime.strftime("%B %d, %Y %H:%M") # "December 11, 2024 15:30"
    ##########################################################

    msg = MIMEMultipart()
    msg["From"] = smtp_sender
    msg["To"] = smtp_list
    #msg["Subject"] = f"Attack Story - {formatted_datetime}"
    msg["Subject"] = f'Attack Story - {environment_name} - {script_start_time.strftime("%B %d, %Y %H:%M")}'
    attach_files(msg,compressed_output)
    if common_globals['unavailable_devices']:
        msg["Subject"] += " With Warnings"
    msg_body=email_body()
    msg.attach(MIMEText(msg_body, 'html'))
    try:
        mailserver = smtplib.SMTP(host=smtp_server,port=smtp_server_port)
    except:
        update_log("Error parsing SMTP server info")
        return

    try:
        if smtp_auth.upper() == "TRUE":
            mailserver.starttls()
            mailserver.ehlo()
            mailserver.login(smtp_sender, smtp_password)
        else:
            mailserver.ehlo()
        mailserver.sendmail(from_addr=smtp_sender,to_addrs=smtp_list.split(","), msg=msg.as_string())
        mailserver.quit()
        update_log("Email sent")
    except smtplib.SMTPAuthenticationError as auth_err:
        update_log(f"SMTP Authentication failed: {auth_err}")
    except smtplib.SMTPException as smtp_err:
        update_log(f"SMTP error occurred: {smtp_err}")
    except Exception as err:
        update_log(f"Email send has failed: {err}")
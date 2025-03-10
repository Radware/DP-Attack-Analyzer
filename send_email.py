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

def attach_files(msg, output_file):
    attachment = open(output_file, "rb")
    file_name = os.path.basename(output_file)

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

def send_email(output_file, attack_count, top_pps, top_gbps, htmlSummary):
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

    subject = f'Attack Story - {environment_name} - {script_start_time.strftime("%B %d, %Y %H:%M")} - [{attack_count} Attacks] - '
    if attack_count > 0:
        subject += f'[Largest Attacks: {top_pps} PPS {round(top_gbps, 3):g} Gbps]'
    if common_globals['unavailable_devices']:
        subject += " With Warnings"
    msg["Subject"] = subject
        
    attach_files(msg,output_file)

    msg_body = f'\r\n\r\n'
    if common_globals['unavailable_devices']:
        msg_body += f"<h2>Warning:<\h2> \r\n\t The following devices were unreachable {', '.join(common_globals['unavailable_devices'])}<\h2>\r\n\r\n"

    msg_body += htmlSummary.replace('<div style="line-height: 1.5; text-align: center;">','<div style="line-height: 1.5; text-align: left; width: 95%;">')
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
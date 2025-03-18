using MailKit.Net.Smtp;
using MimeKit;

namespace BulgariaFreelanceAPI.Services
{
    public class EmailSender: IEmailSender
    {
        private readonly IConfiguration _configuration;

        public EmailSender(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public async Task SendEmailAsync(string email, string subject, string htmlMessage)
        {
            // Read email settings from configuration
            var emailSettings = _configuration.GetSection("EmailSettings");
            var smtpServer = emailSettings["SmtpServer"];
            var port = int.Parse(emailSettings["Port"] ?? "587");
            var senderName = emailSettings["SenderName"];
            var senderEmail = emailSettings["SenderEmail"];
            var username = emailSettings["Username"];
            var password = emailSettings["Password"];

            var mimeMessage = new MimeMessage();
            mimeMessage.From.Add(new MailboxAddress(senderName, senderEmail));
            mimeMessage.To.Add(new MailboxAddress(email, email));
            mimeMessage.Subject = subject;

            var builder = new BodyBuilder { HtmlBody = htmlMessage };
            mimeMessage.Body = builder.ToMessageBody();

            using var client = new SmtpClient();
            // Accept all SSL certificates (for demo purposes; adjust in production)
            client.ServerCertificateValidationCallback = (s, c, h, e) => true;
            await client.ConnectAsync(smtpServer, port, MailKit.Security.SecureSocketOptions.StartTls);
            await client.AuthenticateAsync(username, password);
            await client.SendAsync(mimeMessage);
            await client.DisconnectAsync(true);
        }
    }
}

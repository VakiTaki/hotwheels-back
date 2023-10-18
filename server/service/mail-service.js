const nodeMailer = require("nodemailer");

class MailService {
   constructor() {
      this.transporter = nodeMailer.createTransport({
         host: process.env.SMTP_HOST,
         port: process.env.SMTP_HOST,
         secure: false,
         auth: {
            user: process.env.SMTP_USER,
            pass: process.env.SMTP_PASSWORD
         }
      })
   }
   async sendActivationMail(to, link) {
      this.transporter.sendMail({
         from: process.env.SMTP_USER,
         to,
         subject: `Активация аккаунта на платформе  ${process.env.API_URL}`,
         text: "",
         html: `
         <div>
         <h1>Для активации перейдите по ссылке</h1>
         <a href="${link}">${link}</a>
         </div>
         `
      })
   }
};

module.exports = new MailService();
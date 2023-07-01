class UserMailer < ApplicationMailer

    def send_unban_email(admin,user_email)
        @admin=admin
        @user_email=user_email

        mail(to: @admin.email, subject: 'Unban request from VirusScanner')
    end

end

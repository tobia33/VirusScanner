class UsersController < ApplicationController
    
    def index
        @user=User.all
    end
    
    def destroy
        @user = User.find(params[:id])
        @user.destroy

        if @user.destroy
            redirect_to root_path, notice: "User deleted."
        end
    end

    def ban
        @user=User.find(params[:id])
        User.blocca(@user)
        redirect_to user_path, notice: "User bannato #{@user.access_locked?}"
    end

    def rescan
        @user=User.find(params[:id])
        if @user.has_role?(:not_rescan)
            @user.remove_roles!(:not_rescan)
        else
            @user.roles!(:not_rescan)
        end
        @user.save
        redirect_to user_path #, notice: "User bannato #{@user.access_locked?}"
    end

    def comments
        @user=User.find(params[:id])
        if @user.has_role?(:not_comments)
            @user.remove_roles!(:not_comments)
        else
            @user.roles!(:not_comments)
        end
        @user.save
        redirect_to user_path #, notice: "User bannato #{@user.access_locked?}"
    end

    def votes
        @user=User.find(params[:id])
        if @user.has_role?(:not_votes)
            @user.remove_roles!(:not_votes)
        else
            @user.roles!(:not_votes)
        end
        @user.save
        redirect_to user_path #, notice: "User bannato #{@user.access_locked?}"
    end

    def mitre
        @user=User.find(params[:id])
        if @user.has_role?(:not_mitre)
            @user.remove_roles!(:not_mitre)
        else
            @user.roles!(:not_mitre)
        end
        @user.save
        redirect_to user_path #, notice: "User bannato #{@user.access_locked?}"
    end

    def behavior
        @user=User.find(params[:id])
        if @user.has_role?(:not_behavior)
            @user.remove_roles!(:not_behavior)
        else
            @user.roles!(:not_behavior)
        end
        @user.save
        redirect_to user_path #, notice: "User bannato #{@user.access_locked?}"
    end

    def unlock

        user=User.where(["email == ?",params[:email]]).first
        if user!=nil
            if user.locked_at != nil
                admins = User.all
                admins.each do |admin|
                    if admin.has_role?(:admin)
                        UserMailer.send_unban_email(admin,params[:email]).deliver_now
                    end
                end

                redirect_to root_path, notice: "Admins are processing your request"
            end
        end
    end

end
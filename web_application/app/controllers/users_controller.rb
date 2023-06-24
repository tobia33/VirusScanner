class UsersController < ApplicationController
    def index
        @user=User.all
    end
    
    def destroy
        @user = User.find(params[:id])
        @user.destroy

        if @user.destroy
            redirect_to root_url, notice: "User deleted."
        end
    end

    def ban
        @user=User.find(params[:id])
        if @user.access_locked?
            @user.unlock_access!
        else
            @user.lock_access!
        end
        redirect_to user_path, notice: "User bannato #{@user.access_locked?}"
    end
end
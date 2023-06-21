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
end
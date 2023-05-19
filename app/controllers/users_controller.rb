class UsersController < ApplicationController

  def show
    @user = User.find(params[:id])
    # @u_files = UFile.find_by(user_id: id)
  end

  def new
    # create user form
    @user = User.new
  end
  
  def create
    @user = User.new(user_params)
    if @user.save
      redirect_to @user
    else
      render :new, status: :unprocessable_entity
    end
  end

  def destroy
    @user= User.find(params[:id])
    @user.destroy

    redirect_to root_path, status: :see_other
  end

  private
    def user_params
      params.require(:user).permit(:username, :password, :admin)
    end
  
end

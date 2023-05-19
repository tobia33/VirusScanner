class SessionsController < ApplicationController
  def new
    # login form
    @session = Session.new
  end

  def create
    @user = User.find_by(username: params[:username])
    if @user && @user.authenticate(params[:password])
      @session = Session.new(@user.user_id)
      if @session.save
        
        redirect_to @user
      else
        render :new, status: :unprocessable_entity
      end
    end
  end
end
  

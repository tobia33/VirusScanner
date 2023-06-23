# frozen_string_literal: true

class Users::RegistrationsController < Devise::RegistrationsController
  # before_action :configure_sign_up_params, only: [:create]
  # before_action :configure_account_update_params, only: [:update]

  # GET /resource/sign_up
  def new
    @user=User.new
  end

  # POST /resource
  def create
    @user=User.where(["username == ?",params[:user][:username]])
    if(@user!=[])
      redirect_to new_user_registration_path, notice: "Username already exist" 
      return
    end
    @user = User.new(user_params)
    if params[:user][:email].include?("uniroma1.it")
      @user.roles!(:admin)
    else
      @user.roles!(:normaluser)
    end
    if @user.save
      session[:user_id] = @user.id
      redirect_to root_path, flash: { success: 'Registration successfully' }
    else
      redirect_to new_user_registration_path, notice: "Email already exist"
    end
  end

  # GET /resource/edit
  # def edit
  #   super
  # end

  # PUT /resource
  # def update
  #   super
  # end

  # DELETE /resource
  # def destroy
  #   super
  # end

  # GET /resource/cancel
  # Forces the session data which is usually expired after sign
  # in to be expired now. This is useful if the user wants to
  # cancel oauth signing in/up in the middle of the process,
  # removing all OAuth session data.
  # def cancel
  #   super
  # end

  # protected

  # If you have extra params to permit, append them to the sanitizer.
  # def configure_sign_up_params
  #   devise_parameter_sanitizer.permit(:sign_up, keys: [:attribute])
  # end

  # If you have extra params to permit, append them to the sanitizer.
  # def configure_account_update_params
  #   devise_parameter_sanitizer.permit(:account_update, keys: [:attribute])
  # end

  # The path used after sign up.
  # def after_sign_up_path_for(resource)
  #   super(resource)
  # end

  # The path used after sign up for inactive accounts.
  # def after_inactive_sign_up_path_for(resource)
  #   super(resource)
  # end

  def user_params
    params.require(:user).permit(:username,:email, :password, :password_confirmation)
  end
end

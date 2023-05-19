class UFilesController < ApplicationController

  def new
    @u_file = UFile.new
  end
  
  def create
    # chiamare api per fare uplad file, che returna il file_id
    @u_file = UFile.new(u_file_params)
    @user = User.find_by(id: @u_file.user_id)
    if @u_file.save
      redirect_to @user
    else
      render :new, status: :unprocessable_entity
    end
  end

  def destroy
    @u_file = UFile.find(params[:id])
    @u_file.destroy

    redirect_to root_path, status: :see_other
  end

  private
    def u_file_params
      params.require(:u_file).permit(:name, :hash, :file_id)
    end
end

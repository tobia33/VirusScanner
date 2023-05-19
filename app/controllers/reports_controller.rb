class ReportsController < ApplicationController
  def new
    @report= Report.new
  end


  def create
    # chiamare api per fare report file, che returna il file_id
    @report = Report.new(report_params)
    @u_file = UFile.find_by(id: @report.u_file_id)
    @user = User.find_by(id: @u_file.user_id)
    if @report.save
      redirect_to @user
    else
      render :new, status: :unprocessable_entity
    end
  end
end

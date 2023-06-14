class ReportsController < ApplicationController

  before_action :authenticate_user!

  def index
  end

  def show
    # find report given id
    @report = Report.find(params[:id])
  end
  def destroy
    @report = Report.find(params[:id])
    @report.destroy
    redirect_to past_reports_path, status: :see_other
  end
end

class ReportsController < ApplicationController

  before_action :authenticate_user!

  #load_and_authorize_resource

  def index
  end

  def show
    # find report given id
    @report = Report.find(params[:id])
  end
  def destroy
    @report = Report.find(params[:id])

    user=User.find(session["warden.user.user.key"][0]).first
    if user.id==@report.user_id || user.has_role?(:admin)
      @report.destroy
      redirect_to past_reports_path, status: :see_other
    else
      redirect_to root_path, notice: "you can't destroy this report"
    end
  end
end

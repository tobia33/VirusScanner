class ReportsController < ApplicationController
  def index
  end

  def show
    # find report given id
    @report = Report.find(params[:id])
  end

end

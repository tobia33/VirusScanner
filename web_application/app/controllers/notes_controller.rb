class NotesController < ApplicationController
  def new
    @report = Report.find_by_id(params[:report_id])
  end

  def create
    @report = Report.find_by_id(params[:report_id])
    @report.notes.create(content: params[:note])
    redirect_to @report
  end
  def destroy
    @note = Note.find(params[:id])
    @report = Report.find(@note.report_id)
    user=User.find(session["warden.user.user.key"][0]).first
    if user.id==@report.user_id || user.has_role?(:admin)
      @note.destroy
    else
      redirect_to root_path, notice: "you can't destroy this report"
    end
  end
end

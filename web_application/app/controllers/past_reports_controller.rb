class PastReportsController < ApplicationController
  def index
    @single_reports = []
    
    user=User.find(session["warden.user.user.key"][0]).first
    if user.has_role?(:admin)
      all_reports = Report.all
    else
      all_reports = Report.where("user_id = ?", session["warden.user.user.key"][0])
    end
    
    # rimuovo report che sono in un gruppo
    for report in all_reports do
      if !report.group_id
        @single_reports.push(report)
      end 
    end
    
    # sort reports
    @single_reports = @single_reports.sort_by {|report| report.created_at}
    if params["sort"]
      if params["sort"] == "score"
        @single_reports = @single_reports.sort_by {|report| report.score}
      end
    end
    
    @groups = Group.where("user_id = ?", session["warden.user.user.key"][0])
    
  end



end

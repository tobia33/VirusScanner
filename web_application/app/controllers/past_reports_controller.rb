class PastReportsController < ApplicationController
  def index
    @single_reports = []
    all_reports = Report.all          # poi mettere solo quelli di utente
    for report in all_reports do
      if !report.group_id
        @single_reports.push(report)
      end
    end

    @groups = Group.all           # poi mettere solo quelli di utente
  end
end

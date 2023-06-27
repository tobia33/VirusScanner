class ManageReportsController < ApplicationController
  def download
    id = params[:id]
    @report = Report.find(id)
    content = @report["content"]

    # save file locally
    num = rand(1..10000000).to_s + '_download'
    filename = Rails.root.join('public', num)
    #File.open(filename, 'wb') do |file|
    #  file.write(content)
    #end
    send_data content, filename: "report.json"

    #File.delete(file_path)
    #sleep(1)
    #File.delete("#{filename}")
    #redirect_to @report

  end

  def upload
  end
end

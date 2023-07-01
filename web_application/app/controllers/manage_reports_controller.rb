class ManageReportsController < ApplicationController
  def download
    id = params[:id]
    @report = Report.find(id)
    content = @report["content"]

    send_data content, filename: "report.json"
  end

  def download_group
    id = params[:id]
    @group = Group.find(id)
    group_reports = Report.where("group_id = #{@group["id"]}")

    num = rand(1..10000000).to_s + '_group_download'
    filename = Rails.root.join('public', num)
    File.open(filename, 'wb') do |file|
      file.write("[\n")
      i = 0
      for report in group_reports do
        if i != 0
          file.write(",\n    {\n        ")
        else
          file.write("    {\n        ")
        end
        if report["sha"]
          file.write("\"sha\": \"#{report[:sha]}\",\n        ") 
        else
          file.write("\"url\": \"#{report[:url]}\",\n        ")
        end
        file.write("\"score\": \"#{report[:score]}\"\n    }")
        i = i+1
      end
      file.write("\n]")
    end
    File.open(filename, 'rb') do |file|
      send_data file.read, filename: "group_report.json"
    end
    # delete file locally
    File.delete(Rails.root.join('public', num))
  end

  def new
  end

  def create
    File.open(params[:report].path) do |file|  
      # parse uploaded report
      raw = file.read
      json_parsed = JSON.parse(raw)
      
      begin
      # in case it was originally a binary uploaded by user
        # try to get sha
        sha256 = json_parsed["meta"]["file_info"]["sha256"]

        # calculate score
        score = json_parsed["data"]["attributes"]["stats"]["malicious"]
        
        # create report
        @logged_in = User.find(session["warden.user.user.key"][0])[0]
        @report = @logged_in.reports.create(sha256: sha256, content: raw, score: score)
      rescue
        begin
        # in case it was originally a url
          # get url
          url = json_parsed["meta"]["url_info"]["url"]
      
          # calculate score
          score = json_parsed["data"]["attributes"]["stats"]["malicious"]
          
          # create report
          @logged_in = User.find(session["warden.user.user.key"][0])[0]
          @report = @logged_in.reports.create(url: url, content: raw, score: score)
        rescue
        # in case it was originally a hash
          sha256 = json_parsed["data"][0]["attributes"]["sha256"]

          # calculate score
          score = json_parsed["data"][0]["attributes"]["last_analysis_stats"]["malicious"]

          # create report
          @logged_in = User.find(session["warden.user.user.key"][0])[0]
          @report = @logged_in.reports.create(sha256: sha256, content: raw, score: score)
        end
      end
    end
      
      # save report to database
      if !@report.save
        puts @report.errors.full_messages
        render :new, status: :unprocessable_entity
        return
      end
      redirect_to @report

  end
end

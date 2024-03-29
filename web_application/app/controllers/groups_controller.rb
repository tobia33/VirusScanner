class GroupsController < ApplicationController
  def new

  end

  def create
    # read uploaded file
    uploaded_file = params[:group_file]

    # save file locally
    File.open(Rails.root.join('public', uploaded_file.original_filename), 'wb') do |file|
      file.write(uploaded_file.read)
    end

    # create group
    @logged_in = User.find(session["warden.user.user.key"][0])[0]
    
    puts User.find(session["warden.user.user.key"][0])[0][:id]
    # # save group to the database
    if !@logged_in.save
      puts @group.errors.full_messages
      render :new, status: :unprocessable_entity
      return
    end
    @group = @logged_in.groups.create(file_name: "#{uploaded_file.original_filename}")

    # read lines
    File.readlines("public/#{uploaded_file.original_filename}").each do |line|
      if line.match("^http")
        # line is an url
        url = URI("https://www.virustotal.com/api/v3/urls")
        http = Net::HTTP.new(url.host, url.port)
        http.use_ssl = true
        request = Net::HTTP::Post.new(url)
        request["accept"] = 'application/json'
        request["x-apikey"] = 'aec7480f33d4934bfe8448b447c8319ad6d3b2f113f918010e8422205dd47822'
        request["content-type"] = 'application/x-www-form-urlencoded'
        request.body = "url=#{line}"

        response = http.request(request)
        json_parsed = JSON.parse(response.read_body)
        
        # check if url exists
        begin
          # assume url exists
          file_id = json_parsed["data"]["id"]
        rescue
          # url does not exist
          next
        end
          
          
        # send file id and receive report
        url = URI("https://www.virustotal.com/api/v3/analyses/#{file_id}")
        http = Net::HTTP.new(url.host, url.port)
        http.use_ssl = true
        request = Net::HTTP::Get.new(url)
        request["accept"] = 'application/json'
        request["x-apikey"] = 'aec7480f33d4934bfe8448b447c8319ad6d3b2f113f918010e8422205dd47822'
        
        response = http.request(request)
        json_parsed = JSON.parse(response.read_body)
        status = json_parsed["data"]["attributes"]["status"]

        # wait for the request to be processed by VirusTotal
        while status == "queued"
          sleep(10)
          response = http.request(request)
          json_parsed = JSON.parse(response.read_body)
          status = json_parsed["data"]["attributes"]["status"]
        end

        url = json_parsed["meta"]["url_info"]["url"]
        
        # calculate score
        score = json_parsed["data"]["attributes"]["stats"]["malicious"]
        
        # create report
        @report = @group.reports.create(url: url, content: response.read_body, score: score, user_id: @group["user_id"])

        # get file id
        file_id = json_parsed["meta"]["url_info"]["id"]

        # send file id and receive comments
        url = URI("https://www.virustotal.com/api/v3/urls/#{file_id}/comments?limit=20")

        http = Net::HTTP.new(url.host, url.port)
        http.use_ssl = true
        
        request = Net::HTTP::Get.new(url)
        request["accept"] = 'application/json'
        request["x-apikey"] = 'aec7480f33d4934bfe8448b447c8319ad6d3b2f113f918010e8422205dd47822'
        
        response = http.request(request)
        json_parsed = JSON.parse(response.read_body)

        # if !@report.save
        #   puts @report.errors.full_messages
        #   render :new, status: :unprocessable_entity
        #   return
        # end
        # for every comment of the report, add it to the database
        for comm in json_parsed["data"] do
          @report.comments.create(body: comm["attributes"]["text"])
        end

        # send file id and receive votes
        url = URI("https://www.virustotal.com/api/v3/urls/#{file_id}/votes?limit=40")

        http = Net::HTTP.new(url.host, url.port)
        http.use_ssl = true

        request = Net::HTTP::Get.new(url)
        request["accept"] = 'application/json'
        request["x-apikey"] = 'aec7480f33d4934bfe8448b447c8319ad6d3b2f113f918010e8422205dd47822'

        response = http.request(request)
        json_parsed = JSON.parse(response.read_body)
        
        # for every vote of the report, add it to the database
        for vot in json_parsed["data"] do
            @report.votes.create(verdict: vot["attributes"]["verdict"], value: vot["attributes"]["value"])
        end
        
      else
        # send hash to VirusTotal and receive report
   
        url = URI("https://www.virustotal.com/api/v3/search?query=#{line}")
        
        http = Net::HTTP.new(url.host, url.port)
        http.use_ssl = true
        request = Net::HTTP::Get.new(url)
        request["accept"] = 'application/json'
        request["x-apikey"] = 'aec7480f33d4934bfe8448b447c8319ad6d3b2f113f918010e8422205dd47822'
        
        response = http.request(request)
        json_parsed = JSON.parse(response.read_body)

        
        # check if any report was found
        if json_parsed["data"].any?
          type = json_parsed["data"][0]["type"].to_s
          
          # check if a file corresponding to the hash was found
          if type != "file"
            # the search found a comment or something else but not a file
            next
          else
            sha256 = json_parsed["data"][0]["attributes"]["sha256"]
            
            # calculate score
            score = json_parsed["data"][0]["attributes"]["last_analysis_stats"]["malicious"]
            
            # create report
            @report = @group.reports.create(sha256: sha256, content: response.read_body, score: score, user_id: @group["user_id"])
            puts "================================================================="
            puts @report  
            # send file hash and receive comments
            url = URI("https://www.virustotal.com/api/v3/files/#{sha256}/comments?limit=20")

            http = Net::HTTP.new(url.host, url.port)
            http.use_ssl = true
            
            request = Net::HTTP::Get.new(url)
            request["accept"] = 'application/json'
            request["x-apikey"] = 'aec7480f33d4934bfe8448b447c8319ad6d3b2f113f918010e8422205dd47822'
            
            response = http.request(request)
            json_parsed = JSON.parse(response.read_body)

            # for every comment of the report, add it to the database
            for comm in json_parsed["data"] do
              @report.comments.create(body: comm["attributes"]["text"])
            end

            # send file hash and receive votes
            url = URI("https://www.virustotal.com/api/v3/files/#{sha256}/votes?limit=40")

            http = Net::HTTP.new(url.host, url.port)
            http.use_ssl = true

            request = Net::HTTP::Get.new(url)
            request["accept"] = 'application/json'
            request["x-apikey"] = 'aec7480f33d4934bfe8448b447c8319ad6d3b2f113f918010e8422205dd47822'

            response = http.request(request)
            json_parsed = JSON.parse(response.read_body)
            
            # for every vote of the report, add it to the database
            for vot in json_parsed["data"] do
                @report.votes.create(verdict: vot["attributes"]["verdict"], value: vot["attributes"]["value"])
            end 
          end
        else
          # no results found
          next
        end
      end
    end
    redirect_to @group
  
  end
  def destroy
    @group = Group.find(params[:id])
    @group.destroy
    redirect_to past_reports_path, status: :see_other
  end
  def show
    # find group given id
    @group = Group.find(params[:id])
    @sorted = @group.reports.sort_by {|report| report.created_at}
    if params["sort"]
      if params["sort"] == "score"
        @sorted = @group.reports.sort_by {|report| report.score}
      end
    end
  end
end

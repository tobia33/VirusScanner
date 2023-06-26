class RescanReportsController < ApplicationController
    def show

        current_user=User.find(session[:user_id])
        if current_user.has_role?(:not_rescan)
            redirect_to root_path
        end

        id = Base64.decode64(params[:id])
        if id.match("^http")
            url = URI("https://www.virustotal.com/api/v3/urls")

            http = Net::HTTP.new(url.host, url.port)
            http.use_ssl = true

            request = Net::HTTP::Post.new(url)
            request["accept"] = 'application/json'
            request["x-apikey"] = '06066e396a57d2206a53847e115ace8c42e1c024af45131051e700af1919fccf'
            request["content-type"] = 'application/x-www-form-urlencoded'
            request.body = "url=#{id}"

            response = http.request(request)
            json_parsed = JSON.parse(response.read_body)
            file_id = json_parsed["data"]["id"]                
                
            # send file id and receive report
            url = URI("https://www.virustotal.com/api/v3/analyses/#{file_id}")
            http = Net::HTTP.new(url.host, url.port)
            http.use_ssl = true
            request = Net::HTTP::Get.new(url)
            request["accept"] = 'application/json'
            request["x-apikey"] = '06066e396a57d2206a53847e115ace8c42e1c024af45131051e700af1919fccf'
            
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
            @logged_in = User.find(session["warden.user.user.key"][0])[0]
            @report = @logged_in.reports.create(url: url, content: response.read_body, score: score)

            # save report to the database
            if !@report.save
                puts @report.errors.full_messages
                render :new, status: :unprocessable_entity
                return
            end

            # get file id
            file_id = json_parsed["meta"]["url_info"]["id"]

            # send file id and receive comments
            url = URI("https://www.virustotal.com/api/v3/urls/#{file_id}/comments?limit=20")

            http = Net::HTTP.new(url.host, url.port)
            http.use_ssl = true
            
            request = Net::HTTP::Get.new(url)
            request["accept"] = 'application/json'
            request["x-apikey"] = '06066e396a57d2206a53847e115ace8c42e1c024af45131051e700af1919fccf'
            
            response = http.request(request)
            json_parsed = JSON.parse(response.read_body)

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
            request["x-apikey"] = '06066e396a57d2206a53847e115ace8c42e1c024af45131051e700af1919fccf'

            response = http.request(request)
            json_parsed = JSON.parse(response.read_body)
            
            # for every vote of the report, add it to the database
            for vot in json_parsed["data"] do
                @report.votes.create(verdict: vot["attributes"]["verdict"], value: vot["attributes"]["value"])
            end

           

        else
            url = URI("https://www.virustotal.com/api/v3/files/#{id}/analyse")

            http = Net::HTTP.new(url.host, url.port)
            http.use_ssl = true

            request = Net::HTTP::Post.new(url)
            request["accept"] = 'application/json'
            request["x-apikey"] = '06066e396a57d2206a53847e115ace8c42e1c024af45131051e700af1919fccf'

            response = http.request(request)
            json_parsed = JSON.parse(response.read_body)

            file_id = json_parsed["data"]["id"]

    
            # send file id and receive report
            url = URI("https://www.virustotal.com/api/v3/analyses/#{file_id}")
            http = Net::HTTP.new(url.host, url.port)
            http.use_ssl = true
            request = Net::HTTP::Get.new(url)
            request["accept"] = 'application/json'
            request["x-apikey"] = '06066e396a57d2206a53847e115ace8c42e1c024af45131051e700af1919fccf'
            
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
            
            sha256 = json_parsed["meta"]["file_info"]["sha256"]

            # calculate score
            score = json_parsed["data"]["attributes"]["stats"]["malicious"]

            # create report
            @logged_in = User.find(session["warden.user.user.key"][0])[0]
            @report = @logged_in.reports.create(sha256: sha256, content: response.read_body, score: score)
            
            # save report to database
            if !@report.save
                puts @report.errors.full_messages
                render :new, status: :unprocessable_entity
            return
            end

            # send file hash and receive comments
            url = URI("https://www.virustotal.com/api/v3/files/#{sha256}/comments?limit=20")
            http = Net::HTTP.new(url.host, url.port)
            http.use_ssl = true
            request = Net::HTTP::Get.new(url)
            request["accept"] = 'application/json'
            request["x-apikey"] = '06066e396a57d2206a53847e115ace8c42e1c024af45131051e700af1919fccf'
            
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
            request["x-apikey"] = '06066e396a57d2206a53847e115ace8c42e1c024af45131051e700af1919fccf'
            
            response = http.request(request)
            json_parsed = JSON.parse(response.read_body)
            
            # for every vote of the report, add it to the database
            for vot in json_parsed["data"] do
                @report.votes.create(verdict: vot["attributes"]["verdict"], value: vot["attributes"]["value"])
            end
        end
        
        # redirect to report#show
        redirect_to @report
    end
end
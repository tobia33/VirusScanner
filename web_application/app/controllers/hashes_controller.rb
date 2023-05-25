class HashesController < ApplicationController
  def new
  end

  def create
    # send hash to VirusTotal and receive report
    url = URI("https://www.virustotal.com/api/v3/search?query=#{params[:input_hash]}")
    http = Net::HTTP.new(url.host, url.port)
    http.use_ssl = true
    request = Net::HTTP::Get.new(url)
    request["accept"] = 'application/json'
    request["x-apikey"] = '06066e396a57d2206a53847e115ace8c42e1c024af45131051e700af1919fccf'

    response = http.request(request)
    json_parsed = JSON.parse(response.read_body)
    
    # check if any report was found
    if json_parsed["data"].any?
      type = json_parsed["data"][0]["type"].to_s
      
      # check if a file corresponding to the hash was found
      if type != "file"
        # the search found a comment or something else but not a file
        redirect_to new_hash_path, flash: {notice: "hash incorrect or not present in the database"}
      else
        sha256 = json_parsed["data"][0]["attributes"]["sha256"]
        data = json_parsed["data"][0].to_s
        
        # create report
        @report = Report.new(sha256: sha256, content: data)
        
        # save report to database
        if !@report.save
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

      # redirect to report#show
      redirect_to @report
      end
    else
      # no results found
      redirect_to new_hash_path, {notice: "hash incorrect or not present in the database"}
    end

  end
end

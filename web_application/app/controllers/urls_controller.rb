class UrlsController < ApplicationController
  def new
  end

  def create
    # send url to VirusTotal and retrive file id
    url = URI("https://www.virustotal.com/api/v3/urls")
    http = Net::HTTP.new(url.host, url.port)
    http.use_ssl = true
    request = Net::HTTP::Post.new(url)
    request["accept"] = 'application/json'
    request["x-apikey"] = '06066e396a57d2206a53847e115ace8c42e1c024af45131051e700af1919fccf'
    request["content-type"] = 'application/x-www-form-urlencoded'
    request.body = "url=#{params[:url]}"

    response = http.request(request)
    json_parsed = JSON.parse(response.read_body)
    
    # check if url exists
    begin
      # assume url exists
      file_id = json_parsed["data"]["id"]
    rescue
      # url does not exist
      redirect_to new_url_path, flash: {notice: "url not existent"}
      return
    end
      
      
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
    
    # redirect to report#show
    redirect_to @report
  end
end

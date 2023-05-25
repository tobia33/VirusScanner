

class BinariesController < ApplicationController

  def new
  end

  def create
    # read uploaded file
    uploaded_file = params[:binary]

    # save file locally
    File.open(Rails.root.join('public', uploaded_file.original_filename), 'wb') do |file|
      file.write(uploaded_file.read)
    end
    # send file to VirusTotal API and receive file id
    uri = URI("https://www.virustotal.com/api/v3/files")
    request = Net::HTTP::Post::Multipart.new uri.request_uri, "file" => UploadIO.new("public/#{uploaded_file.original_filename}", "application/octet-stream")
    request["accept"] = 'application/json'
    request["x-apikey"] = '06066e396a57d2206a53847e115ace8c42e1c024af45131051e700af1919fccf'
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
    
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
    data = json_parsed["data"].to_s
    
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
  
end
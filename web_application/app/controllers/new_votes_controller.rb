class NewVotesController < ApplicationController
  def new
  end

  def create

    user=User.find(session["warden.user.user.key"][0]).first
    if !user.has_role?(:admin)
      redirect_to root_path
    end

    if params[:sha]
      sha = Base64.decode64(params[:sha])
    end
    if params[:url]
      url = Base64.decode64(params[:url])
    end
    if params[:url] != ""

      uri = URI("https://www.virustotal.com/api/v3/urls")
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true
      request = Net::HTTP::Post.new(uri)
      request["accept"] = 'application/json'
      request["x-apikey"] = 'aec7480f33d4934bfe8448b447c8319ad6d3b2f113f918010e8422205dd47822'
      request["content-type"] = 'application/x-www-form-urlencoded'
      request.body = "url=#{url}"

      response = http.request(request)
      json_parsed = JSON.parse(response.read_body)
      
      file_id = json_parsed["data"]["id"]

      # send file id and receive report
      # necessary to get new file id
      uri = URI("https://www.virustotal.com/api/v3/analyses/#{file_id}")
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true
      request = Net::HTTP::Get.new(uri)
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

      # get file id
      file_id = json_parsed["meta"]["url_info"]["id"]

      # add comment
      uri = URI("https://www.virustotal.com/api/v3/urls/#{file_id}/votes")

      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true

      request = Net::HTTP::Post.new(uri)
      request["accept"] = 'application/json'
      request["content-type"] = 'application/json'
      request["x-apikey"] = 'aec7480f33d4934bfe8448b447c8319ad6d3b2f113f918010e8422205dd47822'

      request.body = "{\"data\":{\"type\":\"vote\",\"attributes\":{\"verdict\":\"#{params[:vote]}\"}}}"

      response = http.request(request)
    else

      uri = URI("https://www.virustotal.com/api/v3/files/#{sha}/votes")

      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true

      request = Net::HTTP::Post.new(uri)
      request["accept"] = 'application/json'
      request["content-type"] = 'application/json'
      request["x-apikey"] = 'aec7480f33d4934bfe8448b447c8319ad6d3b2f113f918010e8422205dd47822'
      request.body = "{\"data\":{\"type\":\"vote\",\"attributes\":{\"verdict\":\"#{params[:vote]}\"}}}"

      response = http.request(request)
      puts "//////////////////////////////////////////"
      puts response.read_body
    end
    # redirect to report#show
    @report = Report.find_by_id(params[:report_id])
    redirect_to @report
  end
  def destroy
    @vote = Vote.find(params[:id])
    @report = Report.find(@vote.report_id)
    user=User.find(session["warden.user.user.key"][0]).first
    if user.id==@report.user_id || user.has_role?(:admin)
      @vote.destroy
    else
      redirect_to root_path, notice: "you can't destroy this report"
    end
  end
end

class BehaviorReportsController < ApplicationController
  def show
    
    current_user=User.find(session["warden.user.user.key"][0]).first
    if current_user.has_role?(:not_behavior)
      redirect_to root_path
    end

    url = URI("https://www.virustotal.com/api/v3/files/#{params[:id]}/behaviour_summary")

    http = Net::HTTP.new(url.host, url.port)
    http.use_ssl = true

    request = Net::HTTP::Get.new(url)
    request["accept"] = 'application/json'
    request["x-apikey"] = 'aec7480f33d4934bfe8448b447c8319ad6d3b2f113f918010e8422205dd47822'

    response = http.request(request)
    @behavior_report = response.read_body
  end
end

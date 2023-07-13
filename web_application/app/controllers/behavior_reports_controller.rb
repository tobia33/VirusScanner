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
    request["x-apikey"] = '06066e396a57d2206a53847e115ace8c42e1c024af45131051e700af1919fccf'

    response = http.request(request)
    @behavior_report = response.read_body
  end
end

class GoogleDrivesController < ApplicationController
  def export
    id = params[:id]
    report = Report.find(id)
    content = report["content"]

    # save file locally
    num = rand(1..10000000).to_s + '_drive_upload'
    filename = Rails.root.join('public', num)
    File.open(filename, 'wb') do |file|
      file.write(content)
    end
    puts filename
    # send file to drive
    uri = URI("https://www.googleapis.com/upload/drive/v3/files?uploadType=media")
    request = Net::HTTP::Post::Multipart.new uri.request_uri, "file" => UploadIO.new("public/#{num}", "application/json")
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
    
    response = http.request(request)
    puts response.read_body
    File.delete("public/#{num}") 
  end

  def import
  end
end

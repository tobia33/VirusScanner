require 'uri'
require 'net/http'
require 'openssl'
require "rubygems"
require "net/http/post/multipart"
require 'json'
class ApplicationController < ActionController::Base
    rescue_from CanCan::AccessDenied do |exception|
        redirect_to root_path, :alert => exception.message
    end
end

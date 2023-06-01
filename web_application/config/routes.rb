Rails.application.routes.draw do


  root "reports#index"

  resources :behavior_reports
  resources :mitre_reports
  resources :groups
  resources :past_reports
  resources :hashes
  resources :urls
  resources :reports
  resources :binaries
  # Define your application routes per the DSL in https://guides.rubyonrails.org/routing.html

  # Defines the root path route ("/")
  # root "articles#index"
end

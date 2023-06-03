Rails.application.routes.draw do


  root "reports#index"

  #get 'rescan_reports/:id', to: 'rescan_reports#show'
  
  resources :rescan_reports
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

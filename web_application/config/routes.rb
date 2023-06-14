Rails.application.routes.draw do
  devise_for :users, :controllers => { 
    :sessions => "users/sessions", 
    :registrations => "users/registrations", 
    :passwords => "users/passwords", 
    :confirmations => "users/confirmations", 
    :unlocks => "users/unlocks"
  } do
    get "/login" => "devise/sessions#new"
    get "/logout" => "devise/sessions#destroy"
  end


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

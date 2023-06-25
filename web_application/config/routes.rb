Rails.application.routes.draw do
  devise_for :users, :controllers => { 
    :sessions => "users/sessions", 
    :registrations => "users/registrations", 
    :passwords => "users/passwords", 
    :confirmations => "users/confirmations", 
    :unlocks => "users/unlocks",
    :omniauth_callbacks => "users/omniauth_callbacks"
    } do
      get "/login" => "devise/sessions#new"
      get "/logout" => "devise/sessions#destroy"
      get "/auth/:provider/callback" => "devise/sessions#create"
      get "session/destroy" => "devise/sessions#destroy"
    end
    
    get "users", to: "users#index"
    delete "users/:id", to: "users#destroy"
    
    
    #get 'rescan_reports/:id', to: 'rescan_reports#show'
    
  get 'google_drives/export', to: "google_drives#export"
  get 'google_drives/import', to: "google_drives#import"

  resources :rescan_reports
  resources :behavior_reports
  resources :mitre_reports
  resources :groups
  resources :past_reports
  resources :hashes
  resources :urls
  resources :reports
  resources :binaries
  resources :users

  resources :users, only: [:index] do
    member do
      patch :ban
    end
  end
  # Define your application routes per the DSL in https://guides.rubyonrails.org/routing.html

  # Defines the root path route ("/")
  # root "articles#index"
  root "reports#index"
end

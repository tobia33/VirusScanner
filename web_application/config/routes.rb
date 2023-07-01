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

    get "user_unlock", to: "users#unlock"
    
    #get 'rescan_reports/:id', to: 'rescan_reports#show'
    
    
    get 'manage_reports/download', to: 'manage_reports#download'
    get 'manage_reports/download_group', to: 'manage_reports#download_group'

    resources :manage_reports
    resources :new_votes
    resources :new_comments
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
      patch :rescan
      patch :votes
      patch :comments
      patch :behavior
      patch :mitre
      post :unlock
    end
  end
  # Define your application routes per the DSL in https://guides.rubyonrails.org/routing.html

  # Defines the root path route ("/")
  root "reports#index"
end

Rails.application.routes.draw do
  get 'reports/new'
  root 'sessions#new'
  # Define your application routes per the DSL in https://guides.rubyonrails.org/routing.html

  resources :users

  #routes u_file
  get "/upload", to: "u_file#new"
  post "/upload", to: "u_file#create"

  # routes session
  get "/login", to: "sessions#new"
  post "/login", to: "sessions#create"
end

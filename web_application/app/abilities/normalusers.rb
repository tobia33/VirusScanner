Canard::Abilities.for(:normaluser) do
  
  cannot [:destroy], Comment
  can [:read, :create], Group
  cannot [:destroy], Group
  can [:read, :create], Report
  cannot [:destroy], Report
  can [:read, :create], User
  cannot [:destroy], User
  
  cannot [:destroy], Vote
end

Canard::Abilities.for(:admin) do
  can [:read, :create, :destroy, :manage, :edit], Comment
  
  can [:create, :destroy], Group
  
  can [:read, :create, :destroy], Report
  
  can [:read, :create, :destroy, :manage], User
  
  can [:read, :create, :destroy, :manage, :edit], Vote
  
end

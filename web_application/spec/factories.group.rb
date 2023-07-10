require 'factories.user'
FactoryBot.define do
    factory(:group) do
        file_name {"rook"}
        association :user, factory: :user
    end
end
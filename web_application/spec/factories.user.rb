require 'factories.report'
FactoryBot.define do
    factory(:user) do
        id {"1"}
        username {"ezio"}
        email {"ezio@mail.it"}
        password {"Gf2ikmcdop987"}
    end
end

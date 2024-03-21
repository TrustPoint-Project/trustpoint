from ninja import NinjaAPI


api = NinjaAPI()


api.add_router('/pki/', 'pki.api.router')
